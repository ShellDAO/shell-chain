#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
cargo test --locked -p shell-node --features rocksdb header_batch_source_binding -- --nocapture
