# syntax=docker/dockerfile:1

# Build the rust-api binary. The Rust version matches `rust-version` in
# Cargo.toml.
FROM rust:1.89-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin rust-api

# Run the binary on a small Debian base image as an unprivileged user.
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 rust-api \
    && useradd --uid 10001 --gid rust-api --no-create-home --shell /usr/sbin/nologin rust-api

COPY --from=builder /src/target/release/rust-api /usr/local/bin/rust-api
# This file is a reference only. Mount the real configuration at
# /etc/rust-api/config.toml.
COPY --from=builder /src/config.example.toml /usr/share/rust-api/config.example.toml

USER rust-api:rust-api
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/rust-api"]
CMD ["serve", "--config", "/etc/rust-api/config.toml"]
