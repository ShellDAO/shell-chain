#!/usr/bin/env bash
# Requires the stable Rust toolchain, locked dependencies and the RocksDB feature.
# Preparation creates independent memory-only test keys and a funded chain10.
# Nonzero exit means a step failed; preparation refuses any existing output.
set -euo pipefail
if [[ $# != 2 || ( $1 != prepare && $1 != capture && $1 != pause && $1 != resume && $1 != verify && $1 != refuse && $1 != publish ) ]]; then
  echo "usage: $0 prepare|capture|pause|resume|verify|refuse|publish output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --locked --release -p shell-node --features rocksdb --example mldsa-produce-proof
exec "${CARGO_TARGET_DIR:-target}/release/examples/mldsa-produce-proof" "$1-both-slh" "$2"
