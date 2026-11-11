#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ( $1 != prepare && $1 != capture && $1 != pause && $1 != resume && $1 != verify && $1 != refuse && $1 != publish ) ]]; then
  echo "usage: $0 prepare|capture|pause|resume|verify|refuse|publish output" >&2
  exit 2
fi
cd "$(dirname "$0")/../.."
cargo build --locked --release -p shell-node --features rocksdb --example mldsa-produce-proof
mode="$1-slh-proposer"
exec "${CARGO_TARGET_DIR:-target}/release/examples/mldsa-produce-proof" "$mode" "$2"
