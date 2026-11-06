#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo test --locked -p shell-core commitment::tests::
cargo test --locked -p shell-storage block_commitment
cargo test --locked -p shell-genesis block_commitment
cargo test --locked -p shell-node --features rocksdb block_commitment
cargo test --locked -p shell-cli block_commitment
