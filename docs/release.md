# Release workflow

This repository uses two tools for a release. Cocogitto (`cog`) prepares the
version and the changelog. [cargo-dist](https://opensource.axo.dev/cargo-dist/)
version 0.32.0 packages and publishes the release. The dist configuration is
in [`dist-workspace.toml`](../dist-workspace.toml). The generated workflow is
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Quick start

Run these commands on `main`:

```bash
cog bump --dry-run --auto
make release
```

The first command shows the next version and changes nothing. The second
updates `CHANGELOG.md`, creates a version commit, and creates a tag with
the `v` prefix. It also prints the dist artifact plan. See
[Version and changelog](#version-and-changelog) for the full steps.

## Version and changelog

Run this command on `main` when CI passes:

```bash
make release
```

The target runs two commands:

1. `cog bump --auto` writes `CHANGELOG.md`, creates the version commit, and
   creates a version tag that matches `v*`, for example `v1.2.3`.
2. `dist plan --output-format=human` prints the artifact plan for that
   version.

Cog also checks commit messages. `.githook/commit-msg` runs `cog verify`.
`scripts/check-commits.sh` runs `cog check` in CI. Do not edit `CHANGELOG.md`
by hand. Cog generates the file.

## The release flow

Push the tag that cog created. A tag that matches `v*` triggers
`.github/workflows/release.yml`. A pull request also runs the plan step, but
it does not publish artifacts. The workflow follows these steps:

1. The `checks` job calls `ci.yml`. Every publishing job waits for this job.
   A commit that fails CI cannot release.
2. The `plan` job runs `dist host` for a tag or `dist plan` for a pull
   request. It writes the dist manifest and the release targets.
3. The `build-local-artifacts` job builds the platform archives. It waits for
   `checks` and `plan`.
4. The `build-global-artifacts` job builds the global artifacts, such as
   checksums.
5. The `host` job uploads the artifacts and creates the GitHub Release.
6. The `announce` job announces the release.

## The checks gate

The `checks` job in `release.yml` uses `./.github/workflows/ci.yml`. The
`build-local-artifacts` job lists `checks` in its `needs`. The
`release-config` job in `ci.yml` checks both lines. A workflow that drops
either line fails that job. Do not push a tag for a commit that fails CI.

## Run dist locally

Use the mise tasks:

```bash
mise run dist-plan     # print the artifact plan
mise run dist-check    # check that the plan resolves
mise run dist-build    # build the archives into target/distrib/
```

`mise run dist-build` builds for this machine only. The release workflow
builds every configured target. The `cargo-dist` pin in `mise.toml` must
track `cargo-dist-version` in `dist-workspace.toml`.

## Regenerate the workflow

Run this command at the pinned version:

```bash
dist generate
```

The command overwrites `release.yml`. The file is generated, so apply the two
local edits again after every regeneration:

1. Add the `checks` job that calls `./.github/workflows/ci.yml`.
2. Add `checks` to the `needs` of `build-local-artifacts`.

The comments at the top of `release.yml` describe both edits. The
`release-config` job fails when an edit is missing. Do not edit the generated
parts of the file.

## Publish

1. Confirm CI passes on `main`.
2. Run `make release`. Cog writes the changelog, creates the version commit,
   and creates the `v*` tag.
3. Push the tag:

```bash
git push origin v1.2.3
```

The workflow builds the archives and creates the GitHub Release. It uses the
generated announcement title and body. The checks gate stops the release when
CI fails.
