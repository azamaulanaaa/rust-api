# Local patch: oxkv-s3

This directory is a local copy of the `oxkv-s3` crate at version 0.12.1.
The source is the `v0.12.1` tag of `https://github.com/azamaulanaaa/oxkv`.
The project vendors this crate because crates.io does not publish it.

Local changes:

- Replace the path dependency on `oxkv` with the registry dependency
  `oxkv = { version = "0.12.1", default-features = false }`. The features are
  the same as upstream.
- Remove `[lints] workspace = true`. This copy is not a workspace member.
- Remove the `readme` field. The upstream path points outside this copy.
- Remove `publish = false`. The crate is a local path dependency.
- Trim the `object_store` features to `["aws"]`. The project uses S3 and
  `InMemory` only.

The `src/lib.rs` file and the license files are unchanged.
