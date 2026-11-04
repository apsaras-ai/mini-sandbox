# Build the executor on glibc older than or equal to the runtime rootfs.
FROM rust:1.90-bookworm AS builder
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 nodejs ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/mini-sandbox /usr/local/bin/mini-sandbox
RUN mkdir -p /workspace /run/mini-sandbox /tmp
