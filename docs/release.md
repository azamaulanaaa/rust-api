# Release workflow

This document describes the release workflow. The repository uses
[`Cocogitto`](https://docs.cocogitto.io/) to check commits, write the
changelog, and bump the version. The command name is `cog`.

## Commit format

Write every commit subject in this form:

```text
<type>(<scope>): <description>
```

`<type>` is one of these values: `feat`, `fix`, `docs`, `test`,
`refactor`, `perf`, `build`, `ci`, `chore`.

`<scope>` is optional. Use a short name for the changed area, for
example `ci` or `hooks`. `<description>` is a short sentence in the
imperative mood. Do not end the subject with a period.

A commit that breaks compatibility adds `!` before the colon:

```text
feat(api)!: remove the old flag
```

A `BREAKING CHANGE:` footer also marks a breaking change.

## Enforcement

The repository enforces the commit format in three places:

- `.githook/commit-msg` runs `cog verify --file` on the message before
  Git creates the commit. A bad message stops the commit.
- `scripts/check-commits.sh` runs `cog check` from `scripts/ci.sh`.
  `make ci` and both Git hooks run this script.
- `.githook/pre-push` runs `scripts/ci.sh` before each push. A bad
  commit in the history stops the push.

Do not use `--no-verify` to skip these checks. The
[check pipeline](ci.md) describes the scripts.

## Changelog

`cog bump` generates `CHANGELOG.md`. Do not edit the file by hand. The
Markdown check skips this file. The file has no entry until the first
release.

## Versioning

`cog` selects the next version from the commit types:

- `fix` bumps PATCH.
- `feat` bumps MINOR.
- `!` or `BREAKING CHANGE:` bumps MAJOR.

Tags have the `v` prefix, for example `v1.2.3`.

`cog bump --auto` never jumps from `0.y.z` to `1.0.0`. The `0.y.z`
series marks a version before the first stable release.

## Make a release

Run the release on the `main` branch. `cog.toml` permits a bump on that
branch only. Run this command:

```bash
make release
```

The target runs `cog bump --auto`. The command has three steps:

1. It updates `CHANGELOG.md`.
2. It creates a version commit.
3. It creates a tag with the `v` prefix.

No CI release job exists. The release runs on the local machine.

## Optional GitHub Release

A GitHub Release is optional. The local `make release` flow stays the
default. It updates the changelog, creates the version commit, and creates
the tag. It does not create a GitHub Release.

The workflow `.github/workflows/release.yml` creates the release. It runs
only when you opt in. To opt in, push the version tag to GitHub. The tag
must match `v*`, for example `v1.2.3`. Push the tag that `make release`
created:

```bash
git push origin v1.2.3
```

The workflow then creates a GitHub Release for that tag. It uses the
changelog section for that version as the release notes. If the changelog
has no section for the version, the workflow uses the tag name as the
release title.

To stay local, do not push the tag. The workflow does not run. No GitHub
Release is created.

## Dry run

Run this command on the `main` branch to see the next version:

```bash
cog bump --dry-run --auto
```

The command prints the next version and changes nothing. It does not
write the changelog, create a commit, or create a tag.

## First release

The repository has no tag. Select the first version before the first
release. Run one of these commands:

```bash
cog bump --version 1.0.0
cog bump --version 0.1.0
```

The maintainer decides the first version. Use `1.0.0` when the public
interface is stable. Use `0.1.0` when the interface can change.

## Troubleshooting

### `cog` is not on `PATH`

The `cog` command must be on `PATH`. The check prints this message when
the tool is absent:

```text
error: cog is not on PATH. Install cocogitto first.
```

### The commit hook rejects a message

The commit hook runs `cog verify`. Read the error. Write the message in
the commit format. Run this command to correct the last commit:

```bash
git commit --amend
```

Do not use `--no-verify`.

### The Markdown check skips `CHANGELOG.md`

`cog bump` generates the file. The file format can disagree with the
Markdown rules. `scripts/check-markdown.sh` skips the file on purpose.
Do not add the file to the check.
