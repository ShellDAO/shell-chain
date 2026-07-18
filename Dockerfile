# Multi-stage build for shell-node with RocksDB + libp2p
#
# Multi-arch build (M10):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#       -t ghcr.io/shelldao/shell-chain:v0.27.1 --push .
#
# Single-arch local build:
#   docker build -t shell-node:latest .
ARG TARGETPLATFORM
FROM --platform=${TARGETPLATFORM:-linux/amd64} rust:1.93-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 AS builder

# Install RocksDB build dependencies
RUN apt-get update && apt-get install -y \
    clang libclang-dev llvm-dev \
    cmake pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN scripts/build-release-binary.sh

# Runtime image
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update && apt-get install -y \
    ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash shelluser

COPY --from=builder /build/target/release/shell-node /usr/local/bin/shell-node
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV DATADIR=/data
ENV SHARED=/shared

RUN mkdir -p /data /shared && chown shelluser:shelluser /data /shared

USER shelluser

EXPOSE 8545 30303 9090

HEALTHCHECK --interval=10s --timeout=3s --retries=12 --start-period=20s \
    CMD curl -sf -X POST http://localhost:8545 \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        | grep -q '"result"' || exit 1

ENTRYPOINT ["/entrypoint.sh"]
