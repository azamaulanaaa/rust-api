# Casbin patch

## Upstream crate

This directory is a copy of the `casbin` crate, version `2.20.0`, from
crates.io.

## The change

The `rhai` dependency no longer enables these features:

- `unchecked`
- `only_i32`
- `no_function`
- `no_float`

The retained `rhai` features are `sync`, `no_optimize`, `no_module`, and
`serde`.

No Rust source file differs from upstream.
The manifest also omits the bench, example, profile, and dev-only sections
that a dependency build does not use.

## Why

Casbin enables the removed features without a condition.
Cargo unifies the features of one package across all dependencies.
The `unchecked` feature removes the Rhai operation, string, array, and map
limits.
The `no_function` feature removes function calls and the call-level limit.
The `only_i32` feature removes 64-bit integers.
The `no_float` feature removes floating-point values.
The rule script engine needs all of these features.
It uses the limits for a deterministic budget.
It uses function calls for the recursion test.
It uses 64-bit integers for Unix timestamps.

## Update procedure

1. Take the `Cargo.toml` from the new upstream release.
2. Remove `unchecked`, `only_i32`, `no_function`, and `no_float` from the
   `rhai` features.
3. Keep `sync`, `no_optimize`, `no_module`, and `serde`.
4. Copy the upstream `src` directory, `LICENSE`, and `README.md`.
5. Update the version in this file and in `Cargo.toml`.
6. Run the full gate:
   - `cargo fmt --all --check`
   - `cargo clippy --all-targets --all-features --locked -- -D warnings`
   - `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked`
   - `cargo test --locked`
7. Check that the script budget tests and the script function tests pass.

## Temporary status

This patch is temporary.
A separate script-evaluator service would remove the need for it.
